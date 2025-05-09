use std::time::Duration;
use humantime::Duration as HumanDuration;
use serde::{Deserialize, Serialize};
use xelis_common::{
    crypto::Hash,
    utils::detect_available_parallelism,
};
use crate::{
    config::{
        CHAIN_SYNC_DEFAULT_RESPONSE_BLOCKS,
        DEFAULT_CACHE_SIZE,
        DEFAULT_P2P_BIND_ADDRESS,
        DEFAULT_RPC_BIND_ADDRESS,
        P2P_DEFAULT_CONCURRENCY_TASK_COUNT_LIMIT,
        P2P_DEFAULT_MAX_PEERS,
        PEER_FAIL_LIMIT,
        PEER_TEMP_BAN_TIME
    },
    p2p::diffie_hellman::{KeyVerificationAction, WrappedSecret}
};

use super::simulator::Simulator;


// Functions helpers for serde default values
fn default_p2p_bind_address() -> String {
    DEFAULT_P2P_BIND_ADDRESS.to_owned()
}

fn default_max_peers() -> usize {
    P2P_DEFAULT_MAX_PEERS
}

fn default_rpc_bind_address() -> String {
    DEFAULT_RPC_BIND_ADDRESS.to_owned()
}

fn default_cache_size() -> usize {
    DEFAULT_CACHE_SIZE
}

fn default_p2p_concurrency_task_count_limit() -> usize {
    P2P_DEFAULT_CONCURRENCY_TASK_COUNT_LIMIT
}

fn default_chain_sync_response_blocks() -> usize {
    CHAIN_SYNC_DEFAULT_RESPONSE_BLOCKS
}

fn default_getwork_rate_limit_ms() -> u64 {
    500
}

fn default_p2p_temp_ban_duration() -> HumanDuration {
    HumanDuration::from(Duration::from_secs(PEER_TEMP_BAN_TIME))
}

fn default_p2p_fail_count_limit() -> u8 {
    PEER_FAIL_LIMIT
}

#[derive(Debug, Clone, clap::Args, Serialize, Deserialize)]
pub struct GetWorkConfig {
    /// Disable GetWork Server (WebSocket for miners).
    #[clap(long)]
    #[serde(rename = "disable", default)]
    pub disable_getwork_server: bool,
    /// Set the rate limit for GetWork server in milliseconds.
    /// In case of high transactions added in mempool, new jobs are rate limited.
    /// If is set to 0 (no limit), any new job will be sent to miners directly.
    #[clap(long, default_value_t = default_getwork_rate_limit_ms())]
    #[serde(
        rename = "rate_limit_ms",
        default = "default_getwork_rate_limit_ms"
    )]
    pub getwork_rate_limit_ms: u64,
    /// Set the concurrency for GetWork server during a new job notification.
    /// Notify concurrently to N miners at a time.
    /// Set to 0 means no limit and will process as one task per miner.
    /// Default is detected based on available parallelism.
    #[clap(long, default_value_t = detect_available_parallelism())]
    #[serde(
        rename = "notify_job_concurrency",
        default = "detect_available_parallelism"
    )]
    pub getwork_notify_job_concurrency: usize,
}

#[derive(Debug, Clone, clap::Args, Serialize, Deserialize)]
pub struct RPCConfig {
    /// GetWork configuration
    /// This is used to configure the GetWork server.
    /// Only available if the RPC is enabled
    #[clap(flatten)]
    pub getwork: GetWorkConfig,
    /// Disable RPC Server
    /// This will also disable the GetWork Server as it is loaded on RPC server.
    #[clap(long)]
    #[serde(rename = "disable", default)]
    pub disable_rpc_server: bool,
    /// RPC bind address to listen for HTTP requests
    #[clap(long, default_value_t = default_rpc_bind_address())]
    #[serde(
        rename = "bind_address",
        default = "default_rpc_bind_address"
    )]
    pub rpc_bind_address: String,
    /// Number of workers to spawn for the HTTP server.
    /// If not provided, it will use the available paralellism.
    #[clap(long, default_value_t = detect_available_parallelism())]
    #[serde(
        rename = "threads",
        default = "detect_available_parallelism"
    )]
    pub rpc_threads: usize,
    /// RPC Server notification events concurrency
    /// This is used to configure the number of concurrent tasks
    /// that will be used to notify the events to the clients.
    /// By default, it will use the available parallelism.
    /// If set to 0, it will be unlimited.
    #[clap(long, default_value_t = detect_available_parallelism())]
    #[serde(
        rename = "notify_events_concurrency",
        default = "detect_available_parallelism"
    )]
    pub rpc_notify_events_concurrency: usize,
}

#[derive(Debug, Clone, clap::Args, Serialize, Deserialize)]
pub struct P2pConfig {
    /// Optional node tag
    /// This is used to identify the node in the network.
    #[clap(long)]
    pub tag: Option<String>,
    /// P2p bind address to listen for incoming connections
    #[clap(long, default_value_t = default_p2p_bind_address())]
    #[serde(
        rename = "bind_address",
        default = "default_p2p_bind_address"
    )]
    pub p2p_bind_address: String,
    /// Number of maximums peers allowed
    #[clap(long, default_value_t = default_max_peers())]
    #[serde(default = "default_max_peers")]
    pub max_peers: usize,
    /// Add a priority node to connect when P2p is started.
    /// A priority node is connected only one time.
    #[clap(long)]
    #[serde(default)]
    pub priority_nodes: Vec<String>,
    /// An exclusive node is connected and its connection is maintained in case of disconnect
    /// it also replaces seed nodes.
    #[clap(long)]
    #[serde(default)]
    pub exclusive_nodes: Vec<String>,
    /// Disable the P2P Server.
    /// No connections will be accepted.
    /// Node will not be able to communicate the network.
    #[clap(long)]
    #[serde(rename = "disable", default)]
    pub disable_p2p_server: bool,
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
    /// Disable P2P outgoing connections from peers.
    /// 
    /// This is useful for seed nodes under heavy load or for nodes that don't want to connect to others.
    #[clap(long)]
    #[serde(
        rename = "disable_outgoing_connections",
        default
    )]
    pub disable_p2p_outgoing_connections: bool,
    /// Limit of concurrent tasks accepting new incoming connections.
    #[clap(long, default_value_t = default_p2p_concurrency_task_count_limit())]
    #[serde(
        rename = "concurrency_task_count_limit",
        default = "default_p2p_concurrency_task_count_limit"
    )]
    pub p2p_concurrency_task_count_limit: usize,
    /// Execute a specific action when the P2p Diffie-Hellman Key of a peer is different from our stored one.
    /// By default, it will ignore the key change and update it.
    #[clap(long, value_enum, default_value_t = KeyVerificationAction::Ignore)]
    #[serde(default, rename = "on_dh_key_change")]
    pub p2p_on_dh_key_change: KeyVerificationAction,
    /// P2p DH private key to use.
    /// By default, a newly generated key will be used.
    /// Reusing the same private key will allow to keep the same public key
    /// and avoid the need to re-verify the key with our peers.
    /// This is useful for nodes that want to keep the same public key
    /// across several restarts.
    /// Note that reusing the same key may allow to track your node
    /// across your IP changes.
    #[clap(long)]
    #[serde(rename = "dh_private_key")]
    pub p2p_dh_private_key: Option<WrappedSecret>,
    /// P2P Concurrency to use during streams.
    /// This is used to configure the number of concurrent tasks
    /// that will be used to process the streams.
    /// By default, it will use the available parallelism.
    /// If set to 0, it will be unlimited.
    #[clap(long, default_value_t = detect_available_parallelism())]
    #[serde(
        rename = "stream_concurrency",
        default = "detect_available_parallelism"
    )]
    pub p2p_stream_concurrency: usize,
    /// P2P Time to set when banning a peer temporarily due to the fail count limit reached.
    /// This is used to configure the time to wait before unbanning the peer.
    /// By default, it will be set to 15 minutes.
    #[clap(long, default_value_t = default_p2p_temp_ban_duration())]
    #[serde(
        with = "humantime_serde",
        rename = "temp_ban_duration",
        default = "default_p2p_temp_ban_duration"
    )]
    pub p2p_temp_ban_duration: HumanDuration,
    /// P2P Fail count limit to ban a peer temporarily.
    /// This is used to configure the number of failed requests
    /// before banning the peer temporarily.
    #[clap(long, default_value_t = default_p2p_fail_count_limit())]
    #[serde(
        rename = "fail_count_limit",
        default = "default_p2p_fail_count_limit"
    )]
    pub p2p_fail_count_limit: u8,
    /// Force the P2P to re-execute an orphaned block during chain sync.
    /// If set to true, the P2P server will remove the block from storage
    /// and re-add it to the chain.
    /// This may be useful in case of an issue while syncing
    /// NOTE: In versions 1.17 and below, this was the default behavior.
    #[clap(long)]
    #[serde(default)]
    pub reexecute_blocks_on_sync: bool,
}

#[derive(Debug, Clone, clap::Args, Serialize, Deserialize)]
pub struct Config {
    /// RPC configuration
    #[clap(flatten)]
    pub rpc: RPCConfig,
    /// P2P configuration
    #[clap(flatten)]
    pub p2p: P2pConfig,
    /// Set dir path for blockchain storage.
    /// This will be appended by the network name for the database directory.
    /// It must ends with a slash.
    #[clap(long)]
    pub dir_path: Option<String>,
    /// Set LRUCache size (0 = disabled).
    #[clap(long, default_value_t = default_cache_size())]
    #[serde(default = "default_cache_size")]
    pub cache_size: usize,
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
    /// Force DB flush after each block being added in chain.
    /// Flush after each block added ensure no corruption occurs in case
    /// the daemon is killed.
    #[clap(long)]
    #[serde(default)]
    pub force_db_flush: bool
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