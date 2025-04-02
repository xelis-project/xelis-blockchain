use serde::{Deserialize, Serialize};
use xelis_common::crypto::Hash;
use crate::{
    config::{
        DEFAULT_CACHE_SIZE,
        DEFAULT_P2P_BIND_ADDRESS,
        DEFAULT_RPC_BIND_ADDRESS,
        P2P_DEFAULT_CONCURRENCY_TASK_COUNT_LIMIT,
        P2P_DEFAULT_MAX_PEERS
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

fn default_getwork_rate_limit_ms() -> u64 {
    0
}

#[derive(Debug, Clone, clap::Args, Serialize, Deserialize)]
pub struct RPCConfig {
    /// Disable GetWork Server (WebSocket for miners).
    #[clap(long)]
    #[serde(default)]
    pub disable_getwork_server: bool,
    /// Set the rate limit for GetWork server in milliseconds.
    /// In case of high transactions added in mempool, new jobs are rate limited.
    #[serde(default = "default_getwork_rate_limit_ms")]
    #[clap(long, default_value_t = 0)]
    pub getwork_rate_limit_ms: u64,
    /// Disable RPC Server
    /// This will also disable the GetWork Server as it is loaded on RPC server.
    #[clap(long)]
    #[serde(default)]
    pub disable_rpc_server: bool,
    /// Rpc bind address to listen for HTTP requests
    #[clap(long, default_value_t = String::from(DEFAULT_RPC_BIND_ADDRESS))]
    #[serde(default = "default_rpc_bind_address")]
    pub rpc_bind_address: String,
    /// Number of workers to spawn for the HTTP server.
    /// If not provided, it will use the default value from Actix.
    #[clap(long)]
    pub rpc_threads: Option<usize>
}

#[derive(Debug, Clone, clap::Args, Serialize, Deserialize)]
pub struct P2pConfig {
    /// Optional node tag
    #[clap(long)]
    pub tag: Option<String>,
    /// P2p bind address to listen for incoming connections
    #[clap(long, default_value_t = String::from(DEFAULT_P2P_BIND_ADDRESS))]
    #[serde(default = "default_p2p_bind_address")]
    pub p2p_bind_address: String,
    /// Number of maximums peers allowed
    #[clap(long, default_value_t = P2P_DEFAULT_MAX_PEERS)]
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
    /// Disable the p2p connections.
    #[clap(long)]
    #[serde(default)]
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
    /// Configure the maximum chain response size.
    /// 
    /// This is useful for low devices who want to reduce resources usage
    /// and for high-end devices who want to (or help others to) sync faster.
    #[clap(long)]
    pub max_chain_response_size: Option<usize>,
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
    #[serde(default)]
    pub disable_p2p_outgoing_connections: bool,
    /// Limit of concurrent tasks accepting new incoming connections.
    #[clap(long, default_value_t = P2P_DEFAULT_CONCURRENCY_TASK_COUNT_LIMIT)]
    #[serde(default = "default_p2p_concurrency_task_count_limit")]
    pub p2p_concurrency_task_count_limit: usize,
    /// Execute a specific action when the P2p Diffie-Hellman Key of a peer is different from our stored one.
    /// By default, it will ignore the key change and update it.
    #[clap(long, value_enum, default_value_t = KeyVerificationAction::Ignore)]
    #[serde(default)]
    pub p2p_on_dh_key_change: KeyVerificationAction,
    /// P2p DH private key to use.
    pub p2p_private_key: Option<WrappedSecret>,
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
    #[clap(long, default_value_t = DEFAULT_CACHE_SIZE)]
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
    /// Blocks hahes checkpoints
    /// No rewind can go below any of those checkpoints
    #[serde(default)]
    pub checkpoints: Vec<Hash>,
    /// Disable multi-threading for TXs verifications
    #[clap(long)]
    #[serde(default)]
    pub disable_multi_threads_txs: bool,
    /// Set the multi-threading threads count to use during TXs verifications.
    /// By default, will detect the best value.
    /// Unused if multi-thread is disabled.
    #[clap(long)]
    pub txs_threads_count: Option<usize>,
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
    pub recovery_mode: bool
}