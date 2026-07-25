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

fn default_p2p_outgoing_connection_timeout() -> HumanDuration {
    HumanDuration::from(Duration::from_millis(PEER_TIMEOUT_INIT_OUTGOING_CONNECTION))
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

// Default maximum mempool memory usage (512 MiB).
const fn default_mempool_max_memory_usage() -> u64 {
    512 * 1024 * 1024
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
    /// Disable the GetWork websocket server used by miners.
    #[clap(name = "disable-getwork-server", long)]
    #[serde(default)]
    pub disable: bool,
    /// Disable heartbeat checks for GetWork miner websocket sessions.
    #[clap(name = "disable-getwork-heartbeat", long)]
    #[serde(default)]
    pub disable_heartbeat: bool,
    /// Minimum delay, in milliseconds, between GetWork job notifications.
    ///
    /// New jobs can be produced quickly when the mempool changes. Use this to
    /// coalesce updates before notifying miners. Set to `0` to send every new
    /// job immediately.
    #[clap(name = "getwork-rate-limit-ms", long, default_value_t = default_getwork_rate_limit_ms())]
    #[serde(default = "default_getwork_rate_limit_ms")]
    pub rate_limit_ms: u64,
    /// Maximum number of miners notified concurrently for each new job.
    ///
    /// Defaults to the detected CPU parallelism. Set to `0` to remove the limit
    /// and spawn one notification task per miner.
    #[clap(name = "getwork-notify-job-concurrency", long, default_value_t = detect_available_parallelism())]
    #[serde(default = "detect_available_parallelism")]
    pub notify_job_concurrency: usize,
}

impl Default for GetWorkConfig {
    fn default() -> Self {
        Self {
            disable: false,
            disable_heartbeat: false,
            rate_limit_ms: default_getwork_rate_limit_ms(),
            notify_job_concurrency: detect_available_parallelism(),
        }
    }
}

#[derive(Debug, Clone, clap::Args, Serialize, Deserialize)]
pub struct PrometheusConfig {
    /// Enable the Prometheus metrics endpoint.
    ///
    /// The endpoint is served by the RPC server, so RPC must also be enabled.
    #[clap(long = "enable-prometheus")]
    #[serde(default)]
    pub enable: bool,
    /// HTTP route used to expose Prometheus metrics.
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
    /// GetWork mining server settings.
    ///
    /// These settings only take effect when the RPC server is enabled.
    #[clap(flatten)]
    pub getwork: GetWorkConfig,
    /// Prometheus metrics endpoint settings.
    #[clap(flatten)]
    pub prometheus: PrometheusConfig,
    /// Disable the RPC server.
    ///
    /// This also disables GetWork and Prometheus because both are served through
    /// the RPC server.
    #[clap(name = "disable-rpc-server", long)]
    #[serde(default)]
    pub disable: bool,
    /// Address and port where the RPC server listens for HTTP and websocket requests.
    #[clap(name = "rpc-bind-address", long, default_value_t = default_rpc_bind_address())]
    #[serde(default = "default_rpc_bind_address")]
    pub bind_address: String,
    /// Number of worker threads used by the RPC HTTP server.
    ///
    /// Defaults to the detected CPU parallelism.
    #[clap(name = "rpc-threads", long, default_value_t = detect_available_parallelism())]
    #[serde(default = "detect_available_parallelism")]
    pub threads: usize,
    /// Maximum number of concurrent RPC event notification tasks.
    ///
    /// Defaults to the detected CPU parallelism. Set to `0` to remove the
    /// concurrency limit.
    #[clap(name = "rpc-notify-events-concurrency", long, default_value_t = detect_available_parallelism())]
    #[serde(default = "detect_available_parallelism")]
    pub notify_events_concurrency: usize,
    /// Maximum number of calls accepted in one JSON-RPC batch request.
    ///
    /// This limits large batches to reduce denial-of-service risk.
    #[clap(name = "rpc-json-rpc-batch-limit", long, default_value_t = default_rpc_batch_limit())]
    #[serde(default = "default_rpc_batch_limit")]
    pub batch_limit: usize,
    /// Maximum number of websocket sessions accepted by each RPC websocket server.
    #[clap(name = "rpc-max-websocket-sessions", long, default_value_t = default_rpc_max_websocket_sessions())]
    #[serde(default = "default_rpc_max_websocket_sessions")]
    pub max_websocket_sessions: usize,
    /// Maximum number of outbound messages queued per websocket session.
    #[clap(name = "rpc-websocket-session-channel-size", long, default_value_t = default_rpc_websocket_session_channel_size())]
    #[serde(default = "default_rpc_websocket_session_channel_size")]
    pub websocket_session_channel_size: usize,
    /// Maximum number of inbound RPC work items queued per websocket session.
    #[clap(name = "rpc-websocket-session-work-queue-size", long, default_value_t = default_rpc_websocket_session_work_queue_size())]
    #[serde(default = "default_rpc_websocket_session_work_queue_size")]
    pub websocket_session_work_queue_size: usize,
    /// Browser origins allowed to call the RPC server through CORS.
    ///
    /// Leave empty to avoid adding CORS allow-origin rules.
    #[clap(name = "rpc-cors-allowed-origins", long)]
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,
    /// Allow private RPC methods intended only for trusted environments.
    ///
    /// Do not expose this on a public RPC endpoint.
    #[clap(name = "rpc-allow-private-methods", long)]
    #[serde(default)]
    pub allow_private_methods: bool,
    /// Allow RPC methods to execute the contract VM against current chain state.
    ///
    /// Currently used by `simulate_contract_invoke`.
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
    /// Proxy address used for outbound P2P peer connections.
    ///
    /// Also set `p2p-proxy` so the daemon knows which proxy protocol to use.
    #[clap(name = "p2p-proxy-address", long)]
    #[serde(default)]
    pub address: Option<String>,
    /// Proxy protocol used for outbound P2P peer connections.
    #[clap(name = "p2p-proxy", long)]
    pub kind: Option<ProxyKind>,
    /// Username used to authenticate to the configured P2P proxy.
    #[clap(name = "p2p-proxy-username", long)]
    pub username: Option<String>,
    /// Password used to authenticate to the configured P2P proxy.
    #[clap(name = "p2p-proxy-password", long)]
    pub password: Option<String>
}

#[derive(Debug, Clone, clap::Args, Serialize, Deserialize)]
pub struct P2pConfig {
    /// Proxy settings for outbound P2P connections.
    #[clap(flatten)]
    pub proxy: ProxyConfig,
    /// Optional label advertised by this node on the P2P network.
    #[clap(long)]
    pub tag: Option<String>,
    /// Address and port where the P2P server listens for incoming peers.
    #[clap(name = "p2p-bind-address", long, default_value_t = default_p2p_bind_address())]
    #[serde(default = "default_p2p_bind_address")]
    pub bind_address: String,
    /// Maximum total number of connected P2P peers.
    #[clap(long, default_value_t = default_max_peers())]
    #[serde(default = "default_max_peers")]
    pub max_peers: usize,
    /// Maximum number of outbound P2P peer connections.
    #[clap(name = "p2p-max-outgoing-peers", long, default_value_t = default_max_outgoing_peers())]
    #[serde(default = "default_max_outgoing_peers")]
    pub max_outgoing_peers: usize,
    /// Priority peer addresses to connect to when P2P starts.
    ///
    /// Priority peers are attempted in addition to normal peer discovery and are
    /// not continuously reconnected unless they are also exclusive peers.
    #[clap(long)]
    #[serde(default)]
    pub priority_nodes: Vec<String>,
    /// Exclusive peer addresses that replace normal peer discovery.
    ///
    /// Connections to exclusive peers are maintained after disconnects. When at
    /// least one exclusive peer is configured, seed nodes and non-exclusive
    /// inbound peers are not accepted.
    #[clap(long)]
    #[serde(default)]
    pub exclusive_nodes: Vec<String>,
    /// Disable the P2P server.
    ///
    /// The daemon will not accept peer connections or participate in network
    /// propagation.
    #[clap(name = "disable-p2p-server", long)]
    #[serde(default)]
    pub disable: bool,
    /// Allow fast sync from a bootstrapped chain state.
    ///
    /// Fast sync does not store all historical blocks or transactions and does
    /// not locally verify the full history. Use only with trusted peers.
    #[clap(long)]
    #[serde(default)]
    pub allow_fast_sync: bool,
    /// Allow boosted chain sync by requesting blocks in parallel.
    ///
    /// This can improve sync speed, but requests blocks before previous blocks
    /// have been validated.
    #[clap(long)]
    #[serde(default)]
    pub allow_boost_sync: bool,
    /// Forward blocks received from priority peers before local verification.
    ///
    /// This reduces propagation latency for trusted priority peers, such as a
    /// pool operating several nodes in different regions.
    #[clap(long)]
    #[serde(default)]
    pub allow_priority_blocks: bool,
    /// Maximum number of blocks returned in one chain sync response.
    ///
    /// Lower values reduce memory and bandwidth spikes. Higher values can help
    /// well-provisioned nodes sync peers faster.
    #[clap(long, default_value_t = default_chain_sync_response_blocks())]
    #[serde(default = "default_chain_sync_response_blocks")]
    pub max_chain_response_size: usize,
    /// Ask peers not to share this node's IP address.
    ///
    /// This helps keep the node out of peer lists and RPC peer responses, but it
    /// can reduce incoming peer discovery.
    #[clap(long)]
    #[serde(default)]
    pub disable_ip_sharing: bool,
    /// Maximum number of concurrent tasks accepting new P2P connections.
    #[clap(name = "p2p-concurrency-task-count-limit", long, default_value_t = default_p2p_concurrency_task_count_limit())]
    #[serde(default = "default_p2p_concurrency_task_count_limit")]
    pub concurrency_task_count_limit: usize,
    /// Action to take when a peer's stored Diffie-Hellman key changes.
    ///
    /// By default the key change is accepted and the stored key is updated.
    #[clap(name = "p2p-on-dh-key-change", long, value_enum, default_value_t = KeyVerificationAction::Ignore)]
    #[serde(default)]
    pub on_dh_key_change: KeyVerificationAction,
    /// Static P2P Diffie-Hellman private key.
    ///
    /// When unset, a fresh key is generated. Reusing a key preserves the same
    /// public identity across restarts and avoids peer re-verification, but it
    /// can also make the node easier to track across IP changes.
    #[clap(name = "p2p-dh-private-key", long)]
    pub dh_private_key: Option<WrappedSecret>,
    /// Maximum number of concurrent tasks used to process P2P streams.
    ///
    /// Defaults to the detected CPU parallelism. Set to `0` to remove the
    /// concurrency limit.
    #[clap(name = "p2p-stream-concurrency", long, default_value_t = detect_available_parallelism())]
    #[serde(default = "detect_available_parallelism")]
    pub stream_concurrency: usize,
    /// Duration of a temporary peer ban after the fail-count limit is reached.
    #[clap(name = "p2p-temp-ban-duration", long, default_value_t = default_p2p_temp_ban_duration())]
    #[serde(
        with = "humantime_serde",
        default = "default_p2p_temp_ban_duration"
    )]
    pub temp_ban_duration: HumanDuration,
    /// Timeout used when initiating outbound P2P peer connections.
    #[clap(name = "p2p-outgoing-connection-timeout", long, default_value_t = default_p2p_outgoing_connection_timeout())]
    #[serde(
        with = "humantime_serde",
        default = "default_p2p_outgoing_connection_timeout"
    )]
    pub outgoing_connection_timeout: HumanDuration,
    /// Number of peer failures allowed before applying a temporary ban.
    #[clap(name = "p2p-fail-count-limit", long, default_value_t = default_p2p_fail_count_limit())]
    #[serde(default = "default_p2p_fail_count_limit")]
    pub fail_count_limit: u8,
    /// Disable re-execution of orphaned blocks during P2P chain sync.
    ///
    /// When enabled, orphaned blocks are not removed and re-added to trigger
    /// execution again.
    #[clap(name = "disable-p2p-reexecute-blocks-on-sync", long)]
    #[serde(default)]
    pub disable_reexecute_blocks_on_sync: bool,
    /// Log level used for P2P block propagation messages.
    #[clap(name = "p2p-block-propagation-log-level", long, value_enum, default_value_t = LogLevel::Debug)]
    #[serde(default = "debug_log_level")]
    pub block_propagation_log_level: LogLevel,
    /// Disable fetching transactions announced through P2P propagation.
    ///
    /// The daemon will ignore propagated transaction announcements, which can
    /// leave the mempool unsynchronized on smaller networks.
    #[clap(name = "disable-p2p-fetching-txs-propagated", long)]
    #[serde(default)]
    pub disable_fetching_txs_propagated: bool,
    /// Handle eligible peer packets in dedicated tasks.
    ///
    /// Order-dependent packets still use a sequential executor. This can reduce
    /// latency during heavy network activity, but may increase resource usage
    /// under high load.
    #[clap(name = "p2p-handle-peer-packets-in-dedicated-task", long)]
    #[serde(default)]
    pub handle_peer_packets_in_dedicated_task: bool,
    /// Enable Snappy compression for large P2P packets.
    ///
    /// Only packets larger than 1 KiB are compressed. This can reduce bandwidth
    /// usage at the cost of additional CPU work.
    #[clap(name = "enable-p2p-compression", long)]
    #[serde(default)]
    pub enable_compression: bool,
    /// Disable serving fast sync data to other nodes.
    #[clap(name = "disable-fast-sync-support", long)]
    #[serde(default)]
    pub disable_fast_sync_support: bool,
    /// Sync chain data only from configured priority peers.
    #[clap(name = "p2p-sync-from-priority-only", long)]
    #[serde(default)]
    pub sync_from_priority_only: bool,
    /// During reorganizations, accept blocks only from configured priority peers.
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
            outgoing_connection_timeout: default_p2p_outgoing_connection_timeout(),
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
    /// Minimum transaction fee per kB accepted by the mempool.
    ///
    /// The value is expressed in atomic units.
    #[clap(long = "mempool-min-fee-per-kb", default_value_t = default_min_fee_per_kb())]
    #[serde(default = "default_min_fee_per_kb")]
    pub min_fee_per_kb: u64,
    /// Maximum time a transaction may stay in the mempool before expiration.
    #[clap(long = "mempool-tx-expiration-time", default_value_t = default_mempool_tx_expiration_time())]
    #[serde(
        with = "humantime_serde",
        default = "default_mempool_tx_expiration_time"
    )]
    pub tx_expiration_time: HumanDuration,
    /// Maximum memory the mempool may use before evicting transactions.
    ///
    /// Accepts raw bytes or human-readable values such as `512 MiB` or `1.5 GiB`.
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
    /// RPC, GetWork, and Prometheus server settings.
    #[clap(flatten)]
    #[serde(default)]
    pub rpc: RPCConfig,
    /// Peer-to-peer networking and chain synchronization settings.
    #[clap(flatten)]
    #[serde(default)]
    pub p2p: P2pConfig,
    /// Transaction mempool policy and resource limits.
    #[clap(flatten)]
    #[serde(default)]
    pub mempool: MempoolConfig,
    /// Base directory used for blockchain storage.
    ///
    /// The network name is appended to this path. The path must end with `/` or
    /// `\`.
    #[clap(long)]
    pub dir_path: Option<String>,
    /// Enable simulator mode with the selected simulator settings.
    ///
    /// Simulator mode skips proof-of-work verification and generates blocks at
    /// the configured block interval.
    #[clap(long)]
    pub simulator: Option<Simulator>,
    /// Skip proof-of-work verification.
    ///
    /// This is unsafe for production nodes.
    #[clap(long)]
    #[serde(default)]
    pub skip_pow_verification: bool,
    /// Print contract logs while contracts execute.
    #[clap(long)]
    #[serde(default)]
    pub enable_contracts_logging: bool,
    /// Enable automatic pruning while keeping at least this many blocks below the tip.
    ///
    /// Pruning runs after new blocks are applied.
    #[clap(long)]
    pub auto_prune_keep_n_blocks: Option<u64>,
    /// Skip transaction verification while building block templates.
    #[clap(long)]
    #[serde(default)]
    pub skip_block_template_txs_verification: bool,
    /// Hex-encoded genesis block used in development networks.
    #[clap(long)]
    pub genesis_block_hex: Option<String>,
    /// Block hash checkpoints that prevent rewinding below known states.
    #[serde(default)]
    #[clap(long)]
    pub checkpoints: Vec<Hash>,
    /// Number of threads used for transaction verification.
    ///
    /// Defaults to the detected CPU parallelism. Set to `1` to run on the main
    /// verification thread.
    #[clap(long, default_value_t = detect_available_parallelism())]
    #[serde(default = "detect_available_parallelism")]
    pub txs_verification_threads_count: usize,
    /// Number of threads used for block pre-verification.
    ///
    /// Defaults to the detected CPU parallelism.
    #[clap(long, default_value_t = detect_available_parallelism())]
    #[serde(default = "detect_available_parallelism")]
    pub pre_verify_block_threads_count: usize,
    /// Check database integrity during chain initialization.
    ///
    /// This scans versioned data to ensure no pointer or version is above the
    /// current topoheight. It can take a long time on large databases and is
    /// skipped when recovery mode is enabled.
    #[clap(long)]
    #[serde(default)]
    pub check_db_integrity: bool,
    /// Start the daemon in recovery mode.
    ///
    /// Recovery mode skips database integrity checks and startup
    /// pre-computations such as tip difficulty and stable height.
    #[clap(long)]
    #[serde(default)]
    pub recovery_mode: bool,
    /// Flush storage to disk every N blocks, based on topoheight.
    ///
    /// With RocksDB, this also compacts pending changes.
    #[clap(long)]
    #[serde(default)]
    pub flush_db_every_n_blocks: Option<u64>,
    /// Disable the transaction zero-knowledge proof cache.
    ///
    /// The cache is enabled by default to avoid verifying the same proofs more
    /// than once.
    #[clap(long)]
    #[serde(default)]
    pub disable_zkp_cache: bool,
    /// Maximum concurrency for general daemon tasks.
    ///
    /// Defaults to the detected CPU parallelism.
    #[clap(long, default_value_t = detect_available_parallelism())]
    #[serde(default = "detect_available_parallelism")]
    pub concurrency: usize,
    /// Enable snapshot buffering during DAG reorganizations.
    ///
    /// Before applying a reorg, the daemon snapshots the current state, applies
    /// the reorg through an in-memory buffer, then flushes the final state to
    /// storage.
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
