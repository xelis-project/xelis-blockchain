use std::ops::ControlFlow;

use argon2::{Params, Argon2, Algorithm, Version};
use lazy_static::lazy_static;
use log::info;
use serde::{Deserialize, Serialize};
#[cfg(feature = "cli")]
use clap::Parser;
use xelis_common::{
    config::VERSION,
    crypto::ecdlp,
    network::Network,
    utils::detect_available_parallelism
};

#[cfg(feature = "cli")]
use xelis_common::prompt::{
    default_logs_datetime_format,
    LogLevel,
    ModuleConfig
};
use crate::precomputed_tables;

pub const DIR_PATH: &str = "wallets/";
pub const XSWD_BIND_ADDRESS: &str = "0.0.0.0:44325";
pub const PASSWORD_HASH_SIZE: usize = 32;
pub const SALT_SIZE: usize = 32;
pub const KEY_SIZE: usize = 32;

// daemon address by default when no specified
pub const DEFAULT_DAEMON_ADDRESS: &str = "http://127.0.0.1:8080";
// Auto reconnect interval in seconds for Network Handler
pub const AUTO_RECONNECT_INTERVAL: u64 = 5;

lazy_static! {
    pub static ref PASSWORD_ALGORITHM: Argon2<'static> = {
        // 15 MB, 16 iterations
        let params = Params::new(15 * 1000, 16, 1, Some(PASSWORD_HASH_SIZE)).unwrap();
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    };
}


// This struct is used to configure the RPC Server
// In case we want to enable it instead of starting
// the XSWD Server
#[cfg(all(feature = "api_server", feature = "cli"))]
#[derive(Debug, clap::Args, Serialize, Deserialize)]
pub struct RPCConfig {
    /// RPC Server bind address
    #[clap(long)]
    pub rpc_bind_address: Option<String>,
    /// username for RPC authentication
    #[clap(long)]
    pub rpc_username: Option<String>,
    /// password for RPC authentication
    #[clap(long)]
    pub rpc_password: Option<String>,
    /// Number of threads to use for the RPC Server
    #[clap(long)]
    pub rpc_threads: Option<usize>
}

// Functions Helpers
fn default_daemon_address() -> String {
    DEFAULT_DAEMON_ADDRESS.to_owned()
}

fn default_precomputed_tables_l1() -> usize {
    precomputed_tables::L1_FULL
}

fn default_log_filename() -> String {
    String::from("xelis-wallet.log")
}

fn default_logs_path() -> String {
    String::from("logs/")
}

#[cfg(feature = "cli")]
#[derive(Debug, clap::Args, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Daemon address to use
    #[cfg(feature = "network_handler")]
    #[clap(long, default_value_t = String::from(DEFAULT_DAEMON_ADDRESS))]
    #[serde(default = "default_daemon_address")]
    pub daemon_address: String,
    /// Disable online mode
    #[cfg(feature = "network_handler")]
    #[clap(long)]
    pub offline_mode: bool,
}

#[cfg(feature = "cli")]
#[derive(Debug, clap::Args, Serialize, Deserialize)]
pub struct PrecomputedTablesConfig {
    /// L1 size for precomputed tables
    /// By default, it is set to 26 (L1_FULL)
    /// At each increment of 1, the size of the table is doubled
    /// L1_FULL = 26, L1_MEDIUM = 18, L1_LOW = 13
    #[clap(long, default_value_t = precomputed_tables::L1_FULL)]
    #[serde(default = "default_precomputed_tables_l1")]
    pub precomputed_tables_l1: usize,
    /// Set the path to use for precomputed tables
    /// 
    /// By default, it will be from current directory.
    #[clap(long)]
    pub precomputed_tables_path: Option<String>,
}

#[cfg(feature = "cli")]
#[derive(Debug, clap::Args, Serialize, Deserialize)]
pub struct LogConfig {
    /// Set log level
    #[clap(long, value_enum, default_value_t)]
    #[serde(default)]
    pub log_level: LogLevel,
    /// Set file log level
    /// By default, it will be the same as log level
    #[clap(long, value_enum)]
    pub file_log_level: Option<LogLevel>,
    /// Disable the log file
    #[clap(long)]
    #[serde(default)]
    pub disable_file_logging: bool,
    /// Disable the log filename date based
    /// If disabled, the log file will be named xelis-wallet.log instead of YYYY-MM-DD.xelis-wallet.log
    #[clap(long)]
    #[serde(default)]
    pub disable_file_log_date_based: bool,
    /// Enable the log file auto compression
    /// If enabled, the log file will be compressed every day
    /// This will only work if the log file is enabled
    #[clap(long)]
    #[serde(default)]
    pub auto_compress_logs: bool,
    /// Disable the usage of colors in log
    #[clap(long)]
    #[serde(default)]
    pub disable_log_color: bool,
    /// Disable terminal interactive mode
    /// You will not be able to write CLI commands in it or to have an updated prompt
    #[clap(long)]
    #[serde(default)]
    pub disable_interactive_mode: bool,
    /// Log filename
    /// 
    /// By default filename is xelis-wallet.log.
    /// File will be stored in logs directory, this is only the filename, not the full path.
    /// Log file is rotated every day and has the format YYYY-MM-DD.xelis-wallet.log.
    #[clap(long, default_value_t = default_log_filename())]
    #[serde(default = "default_log_filename")]
    pub filename_log: String,
    /// Logs directory
    /// 
    /// By default it will be logs/ of the current directory.
    /// It must end with a / to be a valid folder.
    #[clap(long, default_value_t = default_logs_path())]
    #[serde(default = "default_logs_path")]
    pub logs_path: String,
    /// Module configuration for logs
    #[clap(long)]
    #[serde(default)]
    pub logs_modules: Vec<ModuleConfig>,
    /// Disable the ascii art at startup
    #[clap(long)]
    #[serde(default)]
    pub disable_ascii_art: bool,
    /// Change the datetime format used by the logger
    #[clap(long, default_value_t = default_logs_datetime_format())]
    #[serde(default = "default_logs_datetime_format")]
    pub datetime_format: String,
}

#[cfg(feature = "cli")]
#[derive(Parser, Serialize, Deserialize)]
#[clap(version = VERSION, about = "XELIS is an innovative cryptocurrency built from scratch with BlockDAG, Homomorphic Encryption, Zero-Knowledge Proofs, and Smart Contracts.")]
#[command(styles = xelis_common::get_cli_styles())]
pub struct Config {
    /// RPC Server configuration
    #[cfg(feature = "api_server")]
    #[structopt(flatten)]
    pub rpc: RPCConfig,
    /// Network Configuration
    #[structopt(flatten)]
    pub network_handler: NetworkConfig,
    /// Precopmuted tables configuration
    #[structopt(flatten)]
    pub precomputed_tables: PrecomputedTablesConfig,
    /// Log configuration
    #[structopt(flatten)]
    pub log: LogConfig,
    /// Set the path for wallet storage to open/create a wallet at this location
    #[clap(long)]
    pub wallet_path: Option<String>,
    /// Password used to open wallet
    #[clap(long)]
    pub password: Option<String>,
    /// Restore wallet using seed
    #[clap(long)]
    pub seed: Option<String>,
    /// How many threads we want to use
    /// during ciphertext decryption
    #[clap(long, default_value_t = detect_available_parallelism())]
    #[serde(default = "detect_available_parallelism")]
    pub n_decryption_threads: usize,
    /// Concurrency configuration for Network Handler
    #[clap(long, default_value_t = detect_available_parallelism())]
    #[serde(default = "detect_available_parallelism")]
    pub network_concurrency: usize,
    /// Network selected for chain
    #[clap(long, value_enum, default_value_t = Network::Mainnet)]
    #[serde(default)]
    pub network: Network,
    /// XSWD Server configuration
    #[cfg(feature = "api_server")]
    #[clap(long)]
    #[serde(default)]
    pub enable_xswd: bool,
    /// Disable the history scan
    /// This will prevent syncing old TXs/blocks
    /// Only blocks / transactions caught by the network handler will be stored, not the old ones
    #[clap(long)]
    #[serde(default)]
    pub disable_history_scan: bool,
    /// Force the wallet to use a stable balance only during transactions creation.
    /// This will prevent the wallet to use unstable balance and prevent any orphaned transaction due to DAG reorg.
    /// This is only working if the wallet is in online mode.
    #[clap(long)]
    #[serde(default)]
    pub force_stable_balance: bool,
    /// JSON File to load the configuration from
    #[clap(long)]
    #[serde(skip)]
    #[serde(default)]
    pub config_file: Option<String>,
    /// Generate the template at the `config_file` path
    #[clap(long)]
    #[serde(skip)]
    #[serde(default)]
    pub generate_config_template: bool
}

/// This struct is used to log the progress of the table generation
pub struct LogProgressTableGenerationReportFunction;

impl ecdlp::ProgressTableGenerationReportFunction for LogProgressTableGenerationReportFunction {
    fn report(&self, progress: f64, step: ecdlp::ReportStep) -> ControlFlow<()> {
        info!("Progress: {:.2}% on step {:?}", progress * 100.0, step);
        ControlFlow::Continue(())
    }
}